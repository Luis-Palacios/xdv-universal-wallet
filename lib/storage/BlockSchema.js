"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BlockSchema = void 0;
const tslib_1 = require("tslib");
const class_validator_1 = require("class-validator");
class BlockSchema {
}
tslib_1.__decorate([
    class_validator_1.IsNumber()
], BlockSchema.prototype, "$block", void 0);
tslib_1.__decorate([
    class_validator_1.IsString()
], BlockSchema.prototype, "$ref", void 0);
tslib_1.__decorate([
    class_validator_1.IsHexadecimal()
], BlockSchema.prototype, "$signature", void 0);
exports.BlockSchema = BlockSchema;
//# sourceMappingURL=BlockSchema.js.map