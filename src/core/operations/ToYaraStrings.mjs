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

        this.name = "toYaraStrings";
        this.module = "Default";
        this.description =
            "Modifies Strings so they can be used as Yara Strings";
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
                value: "      $s",
            },
            {
                name: "Count up",
                type: "boolean",
                value: false,
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
        const [splitstring, prefix, countup, countupNumber] = args;
        let count = countupNumber - 1;
        return input
            .split(splitstring)
            .map((str) => {
                let pre = prefix;
                count = count + 1;
                if (countup) {
                    pre = `${pre}${count}`;
                }
                return `${pre} = "${str}"`;
            })
            .join("\n");
    }

    /**
     * Highlight toYaraStrings
     *
     * @param {Object[]} pos
     * @param {number} pos[].start
     * @param {number} pos[].end
     * @param {Object[]} args
     * @returns {Object[]} pos
     */
    highlight(pos, args) {
        return pos;
    }

    /**
     * Highlight toYaraStrings in reverse
     *
     * @param {Object[]} pos
     * @param {number} pos[].start
     * @param {number} pos[].end
     * @param {Object[]} args
     * @returns {Object[]} pos
     */
    highlightReverse(pos, args) {
        return pos;
    }
}

export default ToYaraStrings;
