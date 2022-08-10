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

        this.name = "Virus Total Content Search";
        this.module = "Default";
        this.description =
            "Converts UTF8-Encoded Input to a virus total content search string. Module will try to determine if input is a Hex string and convert it accordingly";
        this.infoURL =
            "https://support.virustotal.com/hc/en-us/articles/360001386897-Content-search-VTGrep-";
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
                name: "OR combine",
                type: "boolean",
                value: "true",
            },
            {
                name: "Hex detection",
                type: "boolean",
                value: "true",
            },
        ];
    }

    /**
     * @param {string} input
     * @param {Object[]} args
     * @returns {string}
     */
    run(input, args) {
        const [ascii, wide, orBool, hexDetect] = args;

        if (input === "") {
            return "";
        }

        // Check if input is hex allows skippying bytes ([1-2]) and alternatives (aabb|bbaa)
        if (
            hexDetect &&
            input
                .replace(/\s/g, "")
                .match(
                    /^((([0-9a-fA-F?][0-9a-fA-F?])|(\[\d+-\d+\]))|\(((([0-9a-fA-F?][0-9a-fA-F?])|(\[\d+-\d+\]))+\|?)+\))+$/
                )
        ) {
            return `content: {${input}}`;
        }

        // Appent Brackets if Combine with OR is true
        let searchString = "";
        if (ascii && wide && orBool) {
            searchString += "( ";
        }

        if (ascii === true) {
            searchString += `content: "${input}" `;
        }

        // Append OR if Combine with OR is true
        if (ascii && wide && orBool) {
            searchString += " OR ";
        }

        // Input is wide. Convert to Hex. Could be done with the utils?
        if (wide === true) {
            const hex = Buffer.from(input, "utf16le")
                .toString("hex")
                .slice(0, -2);
            searchString += `content: {${hex}} `;
        }

        // Append Brackets if Combine with OR is true
        if (ascii && wide && orBool) {
            searchString += ") ";
        }
        return searchString;
    }
}

export default Vtsearch;
