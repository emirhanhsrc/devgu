const ALLOWED_ORIGIN = "https://app.example.com";

export function start(target, payload) {
  target.postMessage(payload, ALLOWED_ORIGIN);
  setTimeout(() => console.log("tick"), 100);
  return JSON.parse('{"a":1}');
}

window.addEventListener("message", (event) => {
  if (event.origin !== ALLOWED_ORIGIN) return;
  console.log(event.data);
});

export function isBlocked(url) {
  return url.startsWith("javascript:");
}

localStorage.setItem("theme", "dark");
export const local = "http://localhost:3000";
export const apiUrl = import.meta.env.VITE_API_URL;
export const password = process.env.DB_PASSWORD;
export const form = { password: "password", label: "Enter your password" };
