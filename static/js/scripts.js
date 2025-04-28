// Image Preview and Validation for Event Forms
document.addEventListener('DOMContentLoaded', function() {
    const validateImageBtn = document.getElementById('validateImage');
    const featuredImageInput = document.getElementById('featured_image');
    const imagePreview = document.getElementById('imagePreview');
    const previewPlaceholder = document.getElementById('previewPlaceholder');
    const previewImage = document.getElementById('previewImage');
    
    if (validateImageBtn && featuredImageInput) {
        featuredImageInput.addEventListener('input', function() {
            const imageUrl = this.value.trim();
            
            if (imageUrl) {
                // Show loading state
                if (previewPlaceholder) previewPlaceholder.style.display = 'none';
                if (previewImage) {
                    previewImage.src = '/static/images/loading.gif';
                    previewImage.style.display = 'block';
                }
                
                // Check if it's a Wikimedia Commons URL format
                if (imageUrl.includes('commons.wikimedia.org') || 
                    imageUrl.includes('upload.wikimedia.org')) {
                    // Extract filename
                    let filename = imageUrl.split('/').pop();
                    if (filename.includes('File:')) {
                        filename = filename.replace('File:', '');
                    }
                    if (filename.includes('?')) {
                        filename = filename.split('?')[0];
                    }
                    
                    validateImage(filename);
                } else {
                    // Just try to load the image directly
                    if (previewImage) {
                        previewImage.onload = function() {
                            imagePreview.classList.remove('alert-danger');
                            imagePreview.classList.add('alert-success');
                        };
                        previewImage.onerror = function() {
                            imagePreview.classList.remove('alert-success');
                            imagePreview.classList.add('alert-danger');
                            previewImage.src = '/static/images/image-not-found.png';
                        };
                        previewImage.src = imageUrl;
                    }
                }
            } else {
                // Reset preview
                if (previewPlaceholder) previewPlaceholder.style.display = 'block';
                if (previewImage) previewImage.style.display = 'none';
                imagePreview.classList.remove('alert-success', 'alert-danger');
            }
        });
        
        validateImageBtn.addEventListener('click', function(e) {
            e.preventDefault();
            const imageUrl = featuredImageInput.value.trim();
            
            if (imageUrl) {
                // Check if it's a Wikimedia Commons URL format
                if (imageUrl.includes('commons.wikimedia.org') || 
                    imageUrl.includes('upload.wikimedia.org')) {
                    // Extract filename
                    let filename = imageUrl.split('/').pop();
                    if (filename.includes('File:')) {
                        filename = filename.replace('File:', '');
                    }
                    if (filename.includes('?')) {
                        filename = filename.split('?')[0];
                    }
                    
                    validateImage(filename);
                } else {
                    // Just try to load the image directly
                    if (previewImage) {
                        previewImage.onload = function() {
                            imagePreview.classList.remove('alert-danger');
                            imagePreview.classList.add('alert-success');
                            alert('Image loaded successfully!');
                        };
                        previewImage.onerror = function() {
                            imagePreview.classList.remove('alert-success');
                            imagePreview.classList.add('alert-danger');
                            previewImage.src = '/static/images/image-not-found.png';
                            alert('Could not load image. Please check the URL.');
                        };
                        previewImage.src = imageUrl;
                    }
                }
            }
        });
    }
    
    function validateImage(filename) {
        if (!filename) return;
        
        fetch('/validate_image', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': document.querySelector('meta[name="csrf-token"]').getAttribute('content')
            },
            body: JSON.stringify({ filename: filename })
        })
        .then(response => response.json())
        .then(data => {
            if (data.exists) {
                if (previewImage) {
                    previewImage.src = data.preview_url;
                    previewImage.style.display = 'block';
                }
                if (previewPlaceholder) previewPlaceholder.style.display = 'none';
                imagePreview.classList.remove('alert-danger');
                imagePreview.classList.add('alert-success');
            } else {
                if (previewImage) {
                    previewImage.src = '/static/images/image-not-found.png';
                    previewImage.style.display = 'block';
                }
                if (previewPlaceholder) previewPlaceholder.style.display = 'none';
                imagePreview.classList.remove('alert-success');
                imagePreview.classList.add('alert-danger');
                
                // Show error message
                if (data.message) {
                    alert(data.message);
                }
            }
        })
        .catch(error => {
            console.error('Error:', error);
            imagePreview.classList.remove('alert-success');
            imagePreview.classList.add('alert-danger');
            if (previewImage) {
                previewImage.src = '/static/images/image-not-found.png';
                previewImage.style.display = 'block';
            }
            if (previewPlaceholder) previewPlaceholder.style.display = 'none';
        });
    }
}); 