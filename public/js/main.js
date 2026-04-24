function showPage() {
    document.body.classList.add('loaded');
}
window.addEventListener("load", showPage);

setTimeout(showPage, 500);
