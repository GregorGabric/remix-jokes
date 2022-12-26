import type { User } from "@prisma/client";
import { createCookieSessionStorage, redirect } from "@remix-run/node";
import { compare, hash } from "bcryptjs";
import { db } from "./db.server";

interface LoginAndRegister {
  username: string;
  password: string;
}
export const login = async ({ password, username }: LoginAndRegister) => {
  const user = await db.user.findUnique({
    where: {
      username,
    },
  });

  if (!user) {
    return null;
  }

  const isValidPassword = await compare(password, user.passwordHash);
  if (!isValidPassword) {
    return null;
  }

  return user;
};

export async function register({ username, password }: LoginAndRegister) {
  const passwordHash = await hash(password, 10);
  const user = await db.user.create({
    data: {
      username,
      passwordHash,
    },
  });
  return {
    id: user.id,
    username: username,
  };
}

const sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret) throw new Error("SESSION_SECRET is not defined");

const storage = createCookieSessionStorage({
  cookie: {
    name: "RJ_session",
    secure: process.env.NODE_ENV === "production",
    secrets: [sessionSecret],
    sameSite: "lax",
    path: "/",
    httpOnly: true,
    maxAge: 60 * 60 * 24 * 30,
  },
});

export const createUserSession = async (
  userId: User["id"],
  redirectTo: string
) => {
  const session = await storage.getSession();
  session.set("userId", userId);
  return redirect(redirectTo, {
    headers: {
      "Set-Cookie": await storage.commitSession(session),
    },
  });
};

function getUserSession(request: Request) {
  return storage.getSession(request.headers.get("Cookie"));
}

export async function getUserId(request: Request) {
  const session = await getUserSession(request);
  const userId = session.get("userId");
  if (!userId || typeof userId !== "string") return null;
  return userId;
}

export async function getUser(request: Request) {
  const userId = await getUserId(request);
  if (typeof userId !== "string") {
    return null;
  }

  try {
    const user = await db.user.findUnique({
      where: { id: userId },
      select: { id: true, username: true },
    });
    return user;
  } catch {
    throw logout(request);
  }
}

export async function logout(request: Request) {
  const session = await getUserSession(request);
  return redirect("/login", {
    headers: {
      "Set-Cookie": await storage.destroySession(session),
    },
  });
}

export async function requireUserId(
  request: Request,
  redirectTo: string = new URL(request.url).pathname
) {
  const session = await getUserSession(request);
  const userId = session.get("userId");
  if (!userId || typeof userId !== "string") {
    const searchParams = new URLSearchParams([["redirectTo", redirectTo]]);
    throw redirect(`/login?${searchParams}`);
  }
  return userId;
}
