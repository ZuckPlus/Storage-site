    document.addEventListener('DOMContentLoaded', () => {
        const shareButtons = document.querySelectorAll('.toggle-share-btn');
        const shareModal = new bootstrap.Modal(document.getElementById('shareModal'));
        const shareMessage = document.getElementById('shareMessage');
        const shareUrl = document.getElementById('shareUrl');

        shareButtons.forEach(button => {
            button.addEventListener('click', async () => {
                const fileId = button.getAttribute('data-file-id');
                const form = button.closest('form');
                const formData = new FormData(form);

                try {
                    const response = await fetch(form.action, {
                        method: 'POST',
                        body: formData,
                    });

                    if (!response.ok) {
                        throw new Error('Failed to toggle sharing.');
                    }

                    const text = await response.text(); // Optional response data
                    const isShared = text.includes('enabled');
                    const url = text.match(/https?:\/\/[^\s]+/g)?.[0]; // Extract URL

                    if (isShared && url) {
                        shareUrl.value = url;
                        navigator.clipboard.writeText(url);
                        shareMessage.textContent = 'Sharing enabled. The URL has been copied to your clipboard.';
                    } else {
                        shareUrl.value = '';
                        shareMessage.textContent = 'Sharing disabled.';
                    }

                    shareModal.show();
                } catch (error) {
                    alert('An error occurred while toggling sharing.');
                    console.error(error);
                }
            });
        });
    });
