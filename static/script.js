document.addEventListener("DOMContentLoaded", function () {
    const form = document.getElementById("urlForm");
    const resultSection = document.getElementById("result-section");
    const predictionDiv = document.getElementById("prediction");

    form.addEventListener("submit", async function (e) {
        e.preventDefault(); // Prevent page reload

        const urlInput = document.getElementById("urlInput").value.trim();

        // Reset result area
        resultSection.style.display = "none";
        predictionDiv.textContent = "";
        
        // Show loading section
        const loadingSection = document.getElementById("loading-section");
        loadingSection.style.display = "block";

        try {
            const response = await fetch("http://127.0.0.1:8000/predict", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ url: urlInput }),
            });

            const data = await response.json();

            // Hide loading section
            loadingSection.style.display = "none";
            
            if (response.ok && data.status === "checking done") {
                // Update prediction result
                predictionDiv.textContent = `Prediction: ${data.prediction}`;
                resultSection.style.display = "block";
            } else {
                const errorSection = document.getElementById("error-section");
                const errorMessage = document.getElementById("error-message");
                errorMessage.textContent = `Error: ${data.message || 'Something went wrong!'}`;
                errorSection.style.display = "block";
            }
        } catch (error) {
            const errorSection = document.getElementById("error-section");
            const errorMessage = document.getElementById("error-message");
            errorMessage.textContent = `Request failed: ${error.message}`;
            errorSection.style.display = "block";

            // Hide loading section
            loadingSection.style.display = "none";
        }
    });
});
