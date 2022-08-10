/**
 * @author humpalum [tobias.michalski@nextron-systems.com]
 * @copyright Crown Copyright 2022
 * @license Apache-2.0
 */

import Operation from "../Operation.mjs";

/**
 * toYaraStrings operation
 */
class ToYaraStrings extends Operation {
    /**
     * ToYaraStrings constructor
     */
    constructor() {
        super();

        this.name = "To Yara Strings";
        this.module = "Default";
        this.description =
            "Modifies Strings so they can be used as YARA Strings";
        this.infoURL = "https://github.com/VirusTotal/yara";
        this.inputType = "string";
        this.outputType = "string";
        this.args = [
            {
                name: "Split delimiter",
                type: "binaryShortString",
                value: "\\n",
            },
            {
                name: "Prefix",
                type: "string",
                value: "$s",
            },
            {
                name: "Spaces",
                type: "number",
                value: "6",
            },
            {
                name: "Count up",
                type: "boolean",
                value: true,
            },
            {
                name: "Count up from",
                type: "number",
                value: 1,
            },
        ];
    }

    /**
     * @param {string} input
     * @param {Object[]} args
     * @returns {string}
     */
    run(input, args) {
        const [splitstring, prefix, spaces, countup, countupNumber] = args;
        let count = countupNumber - 1;
        return input
            .split(splitstring)
            .map((str) => {
                let pre = " ".repeat(spaces) + prefix;
                count = count + 1;
                if (countup) {
                    pre = `${pre}${count}`;
                }
                return `${pre} = "${str}"`;
            })
            .join("\n");
    }
}

export default ToYaraStrings;
