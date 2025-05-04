


document.querySelector('#logout')?.addEventListener("click", function (e) {
    e.preventDefault();
    ajaxGET("/logout", function(){
        window.location.replace('/')
    });
})