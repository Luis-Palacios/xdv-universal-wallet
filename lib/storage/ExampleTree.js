"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.myDocumentTree = void 0;
const did_1 = require("../did");
const DocumentNodeSchema_1 = require("./DocumentNodeSchema");
const LogNodeSchema_1 = require("./LogNodeSchema");
async function myDocumentTree() {
    const did = await did_1.DIDDocumentBuilder
        .createDID({
        issuer: 'idsomething',
        verificationKeys: [],
        authenticationKeys: []
    });
    // initial tree
    const me = Object.assign(Object.assign({}, did), { tag: 'My RSA Key' });
    const meCid = 'Qw1';
    // create document
    const document = DocumentNodeSchema_1.DocumentNodeSchema.create(meCid, {
        items: {
            item1: 'a',
            item2: 'b'
        }
    });
    // create log
    const log = LogNodeSchema_1.LogNodeSchema.create(document, LogNodeSchema_1.EventType.add, 'Added document node');
}
exports.myDocumentTree = myDocumentTree;
//# sourceMappingURL=ExampleTree.js.map