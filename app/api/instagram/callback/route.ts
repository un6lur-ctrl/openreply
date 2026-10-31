import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db/client";
import { getBaseUrl, isUnifiedLogin } from "@/lib/env";
import { canConnectInstagramAccount } from "@/lib/instagram-accounts";
import {
  getAssignedInstagramAccounts,
  getLongLivedToken,
  getUserInfo,
  packAccountToken,
  subscribeInstagramAccountToWebhooks,
} from "@/lib/meta/client";
import {
  encryptToken,
  exchangeCodeForToken,
  verifyOAuthState,
} from "@/lib/meta/oauth";
import { canManageWorkspace } from "@/lib/workspace-access";

export async function GET(request: NextRequest) {
  const code = request.nextUrl.searchParams.get("code");
  const error = request.nextUrl.searchParams.get("error");
  const state = verifyOAuthState(request.nextUrl.searchParams.get("state"));
  const baseUrl = getBaseUrl();

  if (error) {
    return NextResponse.redirect(`${baseUrl}/settings?instagram=denied`);
  }

  if (!code || !state) {
    return NextResponse.redirect(`${baseUrl}/settings?instagram=invalid`);
  }

  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.redirect(`${baseUrl}/login`);
  }

  const membership = await prisma.workspaceMember.findFirst({
    where: {
      workspaceId: state.workspaceId,
      userId: session.user.id,
    },
  });

  if (!membership || !canManageWorkspace(membership.role)) {
    return NextResponse.redirect(`${baseUrl}/settings?instagram=forbidden`);
  }

  try {
    const redirectUri = `${baseUrl}/api/instagram/callback`;

    if (isUnifiedLogin()) {
      // Unified Login: one system-user token covers every Instagram account the
      // client assigned. Connect each one, storing the token together with the
      // account ID so later calls know which account they act on.
      const { accessToken: systemToken } = await exchangeCodeForToken(
        code,
        redirectUri
      );
      const assigned = await getAssignedInstagramAccounts(systemToken);
      if (assigned.length === 0) {
        throw new Error(
          "No Instagram professional account was assigned to the app. Choose an account on the login screen and approve the permissions."
        );
      }

      // System-user tokens do not expire; keep the expiry far out so the
      // refresh cron never picks these accounts up.
      const farFuture = new Date(Date.now() + 10 * 365 * 24 * 60 * 60 * 1000);
      let connected = 0;
      for (const account of assigned) {
        const instagramId = account.id;
        const connection = await canConnectInstagramAccount({
          workspaceId: state.workspaceId,
          instagramId,
        });
        if (!connection.allowed) continue;

        const packed = packAccountToken(instagramId, systemToken);
        let username = account.username ?? instagramId;
        let name = account.name;
        try {
          const info = await getUserInfo(packed);
          username = info.username ?? username;
          name = info.name ?? name;
        } catch (infoError) {
          console.warn("[Instagram Callback] Profile lookup failed:", infoError);
        }

        let subscribed = false;
        try {
          const subscription = await subscribeInstagramAccountToWebhooks(
            instagramId,
            systemToken
          );
          subscribed = Boolean(subscription.success);
        } catch (subscriptionError) {
          console.warn(
            "[Instagram Callback] Webhook subscription failed:",
            subscriptionError
          );
        }

        const unifiedData = {
          username,
          name,
          accessToken: encryptToken(packed),
          tokenExpiresAt: farFuture,
          webhookSubscribed: subscribed,
        };
        const existingAccount = await prisma.instagramAccount.findUnique({
          where: { instagramId },
        });
        if (existingAccount) {
          const updated = await prisma.instagramAccount.updateMany({
            where: {
              id: existingAccount.id,
              workspaceId: state.workspaceId,
              provider: "META",
            },
            data: unifiedData,
          });
          if (!updated.count) continue;
        } else {
          await prisma.instagramAccount.create({
            data: {
              ...unifiedData,
              workspaceId: state.workspaceId,
              instagramId,
              provider: "META",
            },
          });
        }
        connected += 1;
      }

      if (connected === 0) {
        return NextResponse.redirect(
          `${baseUrl}/settings?instagram=already_connected`
        );
      }
      return NextResponse.redirect(`${baseUrl}/dashboard?connected=true`);
    }

    const { accessToken: shortLivedToken } = await exchangeCodeForToken(
      code,
      redirectUri
    );
    const { accessToken: longLivedToken, expiresIn } =
      await getLongLivedToken(shortLivedToken);
    const userInfo = await getUserInfo(longLivedToken);
    // Webhooks and the messaging API key off the professional account ID
    // (user_id), not the app-scoped `id`. Store user_id so comment webhooks
    // can be matched back to this account. Fall back to id if user_id is
    // ever absent.
    const instagramId = userInfo.user_id ?? userInfo.id;
    const connection = await canConnectInstagramAccount({
      workspaceId: state.workspaceId,
      instagramId,
    });

    if (!connection.allowed) {
      return NextResponse.redirect(
        `${baseUrl}/settings?instagram=already_connected`
      );
    }

    const encryptedToken = encryptToken(longLivedToken);
    const tokenExpiresAt = new Date(Date.now() + expiresIn * 1000);

    let webhookSubscribed = false;
    try {
      const subscription = await subscribeInstagramAccountToWebhooks(
        instagramId,
        longLivedToken
      );
      webhookSubscribed = Boolean(subscription.success);
    } catch (subscriptionError) {
      console.warn(
        "[Instagram Callback] Webhook subscription failed:",
        subscriptionError
      );
    }

    const data = {
      username: userInfo.username,
      name: userInfo.name,
      accessToken: encryptedToken,
      tokenExpiresAt,
      webhookSubscribed,
    };
    const existing = await prisma.instagramAccount.findUnique({ where: { instagramId } });
    if (existing) {
      const updated = await prisma.instagramAccount.updateMany({
        where: { id: existing.id, workspaceId: state.workspaceId, provider: 'META' }, data,
      });
      if (!updated.count) return NextResponse.redirect(`${baseUrl}/settings?instagram=already_connected`);
    } else {
      await prisma.instagramAccount.create({ data: { ...data, workspaceId: state.workspaceId, instagramId, provider: 'META' } });
    }

    return NextResponse.redirect(`${baseUrl}/dashboard?connected=true`);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unknown error";
    console.error("[Instagram Callback] Error:", err);
    // The message is the only diagnostic a self-hoster gets for a failed
    // connect, so persist it alongside the other operational events rather
    // than leaving it in server logs they may not be able to reach.
    await prisma.operationalEvent
      .create({
        data: {
          source: "SYSTEM",
          level: "ERROR",
          workspaceId: state.workspaceId,
          message: "Instagram connection failed",
          payload: { reason: message },
        },
      })
      .catch(() => {});

    return NextResponse.redirect(
      `${baseUrl}/settings?instagram=failed&reason=${encodeURIComponent(
        message.slice(0, 200)
      )}`
    );
  }
}
