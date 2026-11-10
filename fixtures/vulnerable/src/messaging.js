export function send(target, payload) {
  target.postMessage(payload, "*"); // expect: JS-MSG-001
}

window.addEventListener("message", (event) => { // expect: JS-MSG-002
  console.log(event.data);
});
