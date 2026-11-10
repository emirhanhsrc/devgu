export function run(code, body) {
  eval(code); // expect: JS-EXEC-001
  const fn = new Function("a", body); // expect: JS-EXEC-001
  setTimeout("tick()", 100); // expect: JS-EXEC-002
  return fn;
}
