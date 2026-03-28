const params = new URLSearchParams(window.location.search);
const url = params.get("url");

document.getElementById("url").textContent = url;

document.getElementById("continue").onclick = () => {
    window.location.href = url;
};

document.getElementById("back").onclick = () => {
    history.back();
};