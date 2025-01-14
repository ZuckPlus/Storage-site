document.addEventListener('DOMContentLoaded', () => {
    const confirmAction = document.getElementById('confirmAction');
    const renameInput = document.getElementById('renameInput');
    let currentAction = null;
    let currentId = null;

    document.querySelectorAll('.rename-file').forEach(button => {
        button.addEventListener('click', () => {
            currentAction = 'rename_file';
            currentId = button.dataset.fileId;
            renameInput.value = button.dataset.fileName;
            document.getElementById('actionModalLabel').textContent = 'Rename File';
            document.getElementById('renameSection').classList.remove('d-none');
        });
    });

    document.querySelectorAll('.rename-folder').forEach(button => {
        button.addEventListener('click', () => {
            currentAction = 'rename_folder';
            currentId = button.dataset.folderName;
            renameInput.value = button.dataset.folderName;
            document.getElementById('actionModalLabel').textContent = 'Rename Folder';
            document.getElementById('renameSection').classList.remove('d-none');
        });
    });

    confirmAction.addEventListener('click', async () => {
        if (currentAction === 'rename_file' || currentAction === 'rename_folder') {
            const newName = renameInput.value.trim();
            const url = currentAction === 'rename_file' ? `/rename_file/${currentId}` : '/rename_folder';
            const payload = currentAction === 'rename_file'
                ? { new_filename: newName }
                : { old_folder_name: currentId, new_folder_name: newName, parent_folder: '' };

            try {
                const response = await fetch(url, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload),
                });

                if (response.ok) {
                    alert('Rename successful.');
                    location.reload();
                } else {
                    const data = await response.json();
                    alert(`Error: ${data.error}`);
                }
            } catch (error) {
                console.error(error);
                alert('An error occurred.');
            }
        }
    });
});
