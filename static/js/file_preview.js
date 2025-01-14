const previewModal = document.getElementById('previewModal');
const previewContainer = document.getElementById('previewContainer');

previewModal.addEventListener('show.bs.modal', function (event) {
    const button = event.relatedTarget; // Button that triggered the modal
    const fileUrl = button.getAttribute('data-file-url');
    const fileType = button.getAttribute('data-file-type');

    if (fileType.startsWith('video/') || fileType.startsWith('audio/')) {
        previewContainer.innerHTML = `
            <${fileType.startsWith('video/') ? 'video' : 'audio'} controls style="max-width: 100%;">
                <source src="${fileUrl}" type="${fileType}">
                Your browser does not support the ${fileType.startsWith('video/') ? 'video' : 'audio'} tag.
            </${fileType.startsWith('video/') ? 'video' : 'audio'}>
        `;
    } else {
        previewContainer.innerHTML = `<p>No preview available for this file type.</p>`;
    }
});

previewModal.addEventListener('hidden.bs.modal', function () {
    previewContainer.innerHTML = ''; // Clear the container when modal is closed
});
