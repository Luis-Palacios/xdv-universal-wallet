"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.LogNodeSchema = exports.EventType = void 0;
const tslib_1 = require("tslib");
const class_validator_1 = require("class-validator");
const moment_1 = tslib_1.__importDefault(require("moment"));
var EventType;
(function (EventType) {
    EventType[EventType["add"] = 0] = "add";
    EventType[EventType["update"] = 1] = "update";
    EventType[EventType["share"] = 2] = "share";
    EventType[EventType["sign"] = 3] = "sign";
    EventType[EventType["encrypt"] = 4] = "encrypt";
    EventType[EventType["tag"] = 5] = "tag";
})(EventType = exports.EventType || (exports.EventType = {}));
class LogNodeSchema {
    static create(parent, logType, log) {
        return Object.assign(new LogNodeSchema(), {
            log,
            $parent: parent,
            eventType: EventType[logType],
            timestamp: moment_1.default().unix(),
        });
    }
}
tslib_1.__decorate([
    class_validator_1.IsNumber(),
    class_validator_1.IsDefined()
], LogNodeSchema.prototype, "timestamp", void 0);
tslib_1.__decorate([
    class_validator_1.IsDefined()
], LogNodeSchema.prototype, "eventType", void 0);
exports.LogNodeSchema = LogNodeSchema;
//# sourceMappingURL=LogNodeSchema.js.map