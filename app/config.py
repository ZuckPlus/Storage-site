# Define allowed file types for security
# Users marked as whitelisted can bypass these restrictions
ALLOWED_FILE_TYPES = {
    # Document Formats
    'txt', 'doc', 'docx', 'odt', 'rtf', 'pdf', 'tex', 'md', 'epub', 'csv', 'xls', 'xlsx', 'xlsm', 'ods',
    'ppt', 'pptx', 'odp', 'pps', 'ppsx', 'key', 'wpd', 'one', 'pub', 'log',

    # Image Formats
    'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'tif', 'psd', 'ai', 'eps', 'svg', 'ico', 'webp', 'raw',
    'cr2', 'nef', 'orf', 'raf', 'heif', 'indd', 'sketch', 'xcf', 'dng',

    # Video Formats
    'mp4', 'mkv', 'avi', 'mov', 'wmv', 'flv', 'f4v', 'swf', 'webm', 'vob', 'mpg', 'mpeg', '3gp', 'ogv',
    'm4v', 'mts', 'm2ts', 'ts', 'divx', 'rm', 'rmvb',

    # Audio Formats
    'mp3', 'wav', 'aac', 'flac', 'ogg', 'm4a', 'wma', 'aiff', 'alac', 'opus', 'mid', 'midi',

    # Compressed Formats
    'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz', 'iso', 'dmg', 'tgz', 'cab', 'lzma', 'apk', 'jar',

    # Executable & System Files
    'exe', 'msi', 'bat', 'sh', 'bin', 'cmd', 'app', 'deb', 'rpm', 'dll', 'sys', 'drv', 'so', 'pkg', 'out',

    # Database Formats
    'db', 'sql', 'sqlite', 'mdb', 'accdb', 'dbf', 'json', 'xml', 'csv', 'yaml', 'yml',

    # Code & Development Files
    'py', 'java', 'cpp', 'c', 'cs', 'php', 'js', 'ts', 'html', 'htm', 'css', 'scss', 'json', 'xml', 'yaml',
    'yml', 'r', 'go', 'swift', 'dart', 'sh', 'bat', 'cmd', 'lua', 'perl', 'pl', 'rb', 'rs', 'kt', 'jsx', 
    'tsx', 'vue', 'scala', 'ini', 'cfg', 'conf', 'toml', 'log',

    # 3D & CAD Formats
    'stl', 'obj', 'fbx', 'gltf', 'glb', 'blend', 'step', 'iges', 'dwg', 'dxf', '3ds', 'max', 'skp',

    # Virtual Machine Disk Images
    'vdi', 'vmdk', 'vhd', 'vhdx', 'qcow2', 'img',

    # Disk Images
    'iso', 'bin', 'cue', 'nrg', 'img', 'dmg',

    # Backup & Archive Files
    'bak', 'tar', 'zip', 'rar', '7z', 'gz', 'bz2', 'xz', 'tgz',

    # Adobe Formats
    'psd', 'ai', 'indd', 'xd', 'pdf', 'fla', 'swf', 'afphoto', 'afdesign',

    # Font Formats
    'ttf', 'otf', 'woff', 'woff2', 'eot', 'fon',

    # Game Files
    'pak', 'vpk', 'wad', 'dat', 'sav', 'map', 'gmx', 'blend',

    # Scientific & Medical
    'fits', 'dicom', 'nii', 'mat', 'hdf5',

    # GIS & Mapping
    'shp', 'geojson', 'kml', 'kmz', 'tif', 'asc', 'gdb', 'mxd'
}
