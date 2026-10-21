import { NextResponse } from "next/server";
import { COOKIE, verifySession } from "@/lib/session";

// Every page and API call needs a valid session, except sign-in itself.
// Access levels: admin = everything; editor = add/edit; viewer = read-only (see lib/roles.js).
export async function middleware(req) {
  const { pathname } = req.nextUrl, method = req.method;
  const isApi = pathname.startsWith("/api/");
  if (pathname === "/login" || pathname.startsWith("/api/auth/")) return NextResponse.next();

  const s = await verifySession(req.cookies.get(COOKIE)?.value);
  if (!s) {
    if (isApi) return NextResponse.json({ errors: ["Please sign in."] }, { status: 401 });
    const url = new URL("/login", req.url);
    if (pathname !== "/") url.searchParams.set("next", pathname);
    return NextResponse.redirect(url);
  }
  const deny = (msg) => (isApi ? NextResponse.json({ errors: [msg] }, { status: 403 }) : NextResponse.redirect(new URL("/", req.url)));
  const write = !["GET", "HEAD", "OPTIONS"].includes(method);
  if (s.level !== "admin") {
    if (pathname.startsWith("/admin") || pathname.startsWith("/api/users") || pathname.startsWith("/api/audit")) return deny("Administrators only.");
    if (write && (method === "DELETE" || pathname.startsWith("/api/settings"))) return deny("Administrators only.");
  }
  if (s.level === "viewer" && write) return deny("Your role is read-only.");
  return NextResponse.next();
}
export const config = { matcher: ["/((?!_next/static|_next/image|favicon.ico|images/).*)"] };
