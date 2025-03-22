// Function with proper sanitization
function displaySearchResults() {
    const urlParams = new URLSearchParams(window.location.search);
    const query = urlParams.get('q');

    // Create a text node instead of using innerHTML
    const searchHeader = document.getElementById('searchHeader');
    searchHeader.textContent = ''; // Clear existing content
    searchHeader.appendChild(document.createTextNode('Search results for: ' + query));

    // Alternatively, use a sanitization library
    // searchHeader.innerHTML = DOMPurify.sanitize('Search results for: ' + query);
}
