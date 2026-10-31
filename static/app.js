// Small helpers for the form. The site still works without this file.
(function () {
  var form = document.getElementById("check-form");
  var box = document.getElementById("text");
  if (!form || !box) return;

  // Example buttons fill the box
  document.querySelectorAll(".chip[data-text]").forEach(function (button) {
    button.addEventListener("click", function () {
      box.value = button.getAttribute("data-text");
      box.focus();
    });
  });

  // Show that something is happening while the server checks
  var submit = form.querySelector("button[type=submit]");
  var label = submit ? submit.textContent : "";

  form.addEventListener("submit", function () {
    if (!submit) return;
    
    // Change label immediately
    submit.textContent = "Checking…";
    
    // Defer disabling to next event loop tick so form POST payload is sent
    setTimeout(function () {
      submit.disabled = true;
    }, 0);
  });

  // Coming back with the Back button should not leave the button stuck
  window.addEventListener("pageshow", function () {
    if (!submit) return;
    submit.disabled = false;
    submit.textContent = label;
  });
})();