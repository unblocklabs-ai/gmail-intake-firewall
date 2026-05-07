const EXECUTABLE_EXTENSIONS = new Set(["app", "bat", "bin", "cmd", "com", "dll", "dmg", "exe", "hta", "lnk", "msi", "scr"]);
const SCRIPT_EXTENSIONS = new Set(["js", "jse", "ps1", "py", "sh", "vbe", "vbs", "wsf"]);
const ARCHIVE_EXTENSIONS = new Set(["7z", "bz2", "gz", "iso", "rar", "tar", "xz", "zip"]);
const MACRO_CAPABLE_EXTENSIONS = new Set(["doc", "docm", "dot", "dotm", "pot", "potm", "ppt", "pptm", "xls", "xlsm", "xlt", "xltm"]);
const MIME_EXTENSION_HINTS = [
    { pattern: /pdf/i, extensions: new Set(["pdf"]) },
    { pattern: /zip|compressed|archive/i, extensions: ARCHIVE_EXTENSIONS },
    { pattern: /msword|wordprocessingml/i, extensions: new Set(["doc", "docx", "docm", "dot", "dotm"]) },
    { pattern: /spreadsheetml|excel/i, extensions: new Set(["xls", "xlsx", "xlsm", "xlt", "xltm"]) },
    { pattern: /presentationml|powerpoint/i, extensions: new Set(["ppt", "pptx", "pptm", "pot", "potm"]) },
    { pattern: /javascript|ecmascript/i, extensions: new Set(["js", "jse"]) },
    { pattern: /x-msdownload|octet-stream/i, extensions: new Set([...EXECUTABLE_EXTENSIONS, ...SCRIPT_EXTENSIONS]) },
];
export function analyzeAttachments(attachments) {
    return attachments.map(analyzeAttachment);
}
export function analyzeAttachment(attachment) {
    const filename = attachment.filename ?? "";
    const extension = extensionFromFilename(filename);
    const isExecutable = extension ? EXECUTABLE_EXTENSIONS.has(extension) : false;
    const isScript = extension ? SCRIPT_EXTENSIONS.has(extension) : false;
    const isArchive = extension ? ARCHIVE_EXTENSIONS.has(extension) : false;
    const isMacroCapable = extension ? MACRO_CAPABLE_EXTENSIONS.has(extension) : false;
    const hasDoubleExtension = doubleExtension(filename);
    const mimeExtensionMismatch = extension ? hasMimeExtensionMismatch(attachment.mimeType, extension) : false;
    const riskHints = [];
    if (isExecutable) {
        riskHints.push("executable_attachment");
    }
    if (isScript) {
        riskHints.push("script_attachment");
    }
    if (isArchive) {
        riskHints.push("archive_attachment");
    }
    if (isMacroCapable) {
        riskHints.push("macro_capable_document");
    }
    if (hasDoubleExtension) {
        riskHints.push("double_extension");
    }
    if (mimeExtensionMismatch) {
        riskHints.push("mime_extension_mismatch");
    }
    if (!attachment.id) {
        riskHints.push("missing_attachment_id");
    }
    const analyzed = {
        ...attachment,
        riskHints,
        hasAttachmentId: Boolean(attachment.id),
    };
    if (extension) {
        analyzed.extension = extension;
    }
    if (isArchive) {
        analyzed.isArchive = true;
    }
    if (isMacroCapable) {
        analyzed.isMacroCapable = true;
    }
    if (isExecutable) {
        analyzed.isExecutable = true;
    }
    if (isScript) {
        analyzed.isScript = true;
    }
    if (hasDoubleExtension) {
        analyzed.hasDoubleExtension = true;
    }
    if (mimeExtensionMismatch) {
        analyzed.mimeExtensionMismatch = true;
    }
    return analyzed;
}
function extensionFromFilename(filename) {
    const match = /\.([a-z0-9]{1,8})$/i.exec(filename);
    return match?.[1]?.toLowerCase();
}
function doubleExtension(filename) {
    const parts = filename.toLowerCase().split(".").filter(Boolean);
    if (parts.length < 3) {
        return false;
    }
    const previous = parts.at(-2);
    const current = parts.at(-1);
    return Boolean(previous && current && (EXECUTABLE_EXTENSIONS.has(current) || SCRIPT_EXTENSIONS.has(current)));
}
function hasMimeExtensionMismatch(mimeType, extension) {
    if (!mimeType) {
        return false;
    }
    const normalized = mimeType.toLowerCase();
    for (const hint of MIME_EXTENSION_HINTS) {
        if (hint.pattern.test(normalized)) {
            return !hint.extensions.has(extension);
        }
    }
    return false;
}
