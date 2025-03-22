// Vulnerable function that updates the search results page
function displaySearchResults() {
    // Get the query parameter from URL
    const URLParams = new URLSearchParams(window.location.search);
    const query = URLParams.get('q');

    // Directly insert the search query into DOM with vulnerable innerHTML
    document.getElementById('searchHeader').innerHTML = "Search results for: " + query;
}

// Example: this could be exploited with: https://instagram.com/search?q=<img src=x onerror=alert(document.cookie)>
