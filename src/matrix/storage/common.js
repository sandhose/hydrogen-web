export const STORE_NAMES = Object.freeze([
    "session",
    "roomState",
    "roomSummary",
    "timelineEvents",
    "timelineFragments",
    "pendingEvents",
]);

export const STORE_MAP = Object.freeze(STORE_NAMES.reduce((nameMap, name) => {
    nameMap[name] = name;
    return nameMap;
}, {}));

export class StorageError extends Error {
    constructor(message, cause, value) {
        let fullMessage = message;
        if (cause) {
            fullMessage += ": ";
            if (cause.name) {
                fullMessage += `(${cause.name}) `;
            }
            fullMessage += cause.message;
        }
        super(fullMessage);
        if (cause) {
            this.errcode = cause.name;
        }
        this.cause = cause;
        this.value = value;
    }
}
