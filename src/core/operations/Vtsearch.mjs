/**
 * @author humpalum [tobias.michalski@nextron-systems.com]
 * @copyright Crown Copyright 2022
 * @license Apache-2.0
 */

import Operation from "../Operation.mjs";
/**
 * vtsearch operation
 */
class Vtsearch extends Operation {
    /**
     * Vtsearch constructor
     */
    constructor() {
        super();

        this.name = "vtsearch";
        this.module = "Default";
        this.description = "Converts Input to a virus total search string";
        this.infoURL = "https://www.virustotal.com/gui/home/search";
        this.inputType = "string";
        this.outputType = "string";
        this.args = [
            {
                name: "ascii",
                type: "boolean",
                value: "true",
            },
            {
                name: "wide",
                type: "boolean",
                value: "true",
            },
            {
                name: "Combine with OR",
                type: "boolean",
                value: "true",
            },
            /* Example arguments. See the project wiki for full details.
            {
                name: "Second arg",
                type: "number",
                value: 42
            }
            */
        ];
    }

    /**
     * @param {string} input
     * @param {Object[]} args
     * @returns {string}
     */
    run(input, args) {
        const [ascii, wide, orBool] = args;
        // Check if input is hex
        if (input.match(/^[0-9a-fA-F\s]+$/)) {
            return `content: {${input}}`;
        }
        let searchString = "";
        if (ascii && wide && orBool) {
            searchString += "( ";
        }
        if (ascii === true) {
            searchString += `content: "${input}" `;
        }
        if (ascii && wide && orBool) {
            searchString += " OR ";
        }
        // Input is wide. Convert to Hex
        if (wide === true) {
            const hex = Buffer.from(input, "utf16le")
                .toString("hex")
                .slice(0, -2);
            searchString += `content: {${hex}} `;
        }
        if (ascii && wide && orBool) {
            searchString += ") ";
        }
        return searchString;
    }
}

export default Vtsearch;
