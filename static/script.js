document.addEventListener('DOMContentLoaded', () => {
    const scanForm = document.getElementById('scanForm');
    const scanBtn = document.getElementById('scanBtn');
    const btnText = scanBtn ? scanBtn.querySelector('.btn-text') : null;
    const loader = scanBtn ? scanBtn.querySelector('.loader') : null;

    if (scanForm) {
        scanForm.addEventListener('submit', (e) => {
            // Show loader
            if (scanBtn && btnText && loader) {
                btnText.style.display = 'none';
                loader.style.display = 'block';
                scanBtn.disabled = true;
                scanBtn.style.opacity = '0.8';
            }
        });
    }

    // Add simple fade-in delay for table rows
    const rows = document.querySelectorAll('tbody tr');
    rows.forEach((row, index) => {
        row.style.opacity = '0';
        row.style.animation = `fadeIn 0.3s ease-in forwards ${index * 0.1}s`;
    });
});

function exportJSON() {
    // Collect data from DOM since we don't have state management in vanilla JS template
    // This is a simplified export
    const data = {
        url: document.querySelector('.highlight').innerText,
        timestamp: new Date().toISOString(),
        stats: {
            forms: document.querySelectorAll('.stat-box .count')[1].innerText,
            xss: document.querySelectorAll('.stat-box .count')[2].innerText,
            sqli: document.querySelectorAll('.stat-box .count')[3].innerText
        },
        // We could parse the tables here, but for now let's just export the summary
        note: "Full raw data export requires API integration."
    };

    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(data, null, 2));
    const downloadAnchorNode = document.createElement('a');
    downloadAnchorNode.setAttribute("href", dataStr);
    downloadAnchorNode.setAttribute("download", "scan_report.json");
    document.body.appendChild(downloadAnchorNode);
    downloadAnchorNode.click();
    downloadAnchorNode.remove();
}
