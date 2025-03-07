import Finder from "whois-link-finder";
import yargs from "yargs";
import FileLogger from "fast-file-logger";
import fs from "fs";
import ipUtils from "ip-sub";

const logger = new FileLogger({
    logRotatePattern: "YYYY-MM-DD",
    filename: "error-%DATE%.log",
    symLink: false,
    directory: "./logs",
    maxRetainedFiles: 100,
    maxFileSizeMB: 100,
    compressOnRotation: false,
    label: "prefixlen-finder",
    useUTC: true,
    format: ({data, timestamp}) => `${timestamp} ${data}`
});


const params = yargs
    .usage("Usage: $0 <command> [options]")

    .command("$0", "Run Prefixlen finder (default)", function () {
        yargs
            .alias("v", "version")
            .nargs("v", 0)
            .describe("v", "Show version number")

            .alias("a", "af")
            .nargs("a", 1)
            .default("a", "4,6")
            .describe("a", "Address family")

            .alias("o", "output")
            .nargs("o", 1)
            .default("o", "result.csv")
            .describe("o", "Output file")

            .alias("c", "cache-whois")
            .nargs("c", 1)
            .default("c", 3)
            .describe("c", "Number of days whois cache validity")

            .alias("g", "cache-file")
            .nargs("g", 1)
            .default("g", 3)
            .describe("g", "Number of days file are cached")

            .alias("l", "cache-location")
            .nargs("l", 1)
            .default("l", ".cache/")
            .describe("l", "Cache directory location")

            .alias("s", "silent")
            .nargs("s", 0)
            .describe("s", "Silent mode, don't print errors")

            .alias("b", "arin-bulk")
            .nargs("b", 0)
            .describe("b", "Use bulk whois data for ARIN: https://www.arin.net/reference/research/bulkwhois/")

            .alias("p", "arin-skip-suballocations")
            .nargs("p", 0)
            .describe("p", "Do not fetch ARIN's sub allocations. You will save considerable time but have a potentially partial output.")

            .alias("q", "detect-suballocations-locally")
            .nargs("q", 0)
            .describe("q", "Detect ARIN's sub allocations locally instead of downloading a dump file.")

            .alias("d", "download-timeout")
            .nargs("d", 1)
            .describe("d", "Interrupt downloading a geofeed file after seconds")

            .alias("i", "include")
            .nargs("i", 1)
            .default("i", "ripe,apnic,lacnic,afrinic,arin")
            .describe("i", "Include RIRs (comma-separated list)");
    })
    .help("h")
    .alias("h", "help")
    .epilog("Copyright (c) 2024, Massimo Candela")
    .argv;

const options = {
    logger,
    cacheDir: params.l || ".cache/",
    whoisCacheDays: parseInt(params.c),
    daysWhoisSuballocationsCache: 30, // Cannot be less than 7
    compileSuballocationLocally: !!params.q,
    skipSuballocations: !!params.p,
    fileCacheDays: parseInt(params.g),
    arinBulk: params.b,
    af: params.a.toString().split(",").map(i => parseInt(i)),
    silent: !!params.s,
    include: (params.i ?? "ripe,apnic,lacnic,afrinic,arin").split(","),
    output: params.o || "result.csv",
    test: params.t || null,
    specialKeys: ["prefixlen", "Prefixlen"],
    parseLine: (inetnum, data) => {

        const items = data.split(/\r?\n/)
            .filter(i => !!i && !i.startsWith("#") && i.trim() !== "")
            .map(i => i.split(","));

        return items
            .map(([prefix, len]) => {
                return {
                    inetnum,
                    prefix,
                    len
                };
            })
            .filter(({inetnum, prefix}) => ipUtils.getAddressFamily(inetnum) === ipUtils.getAddressFamily(prefix));
    },
    downloadTimeout: params.d || 10 // 0 is not a valid value
};

new Finder(options)
    .run()
    .then(Finder.setEntryPriority)
    .then(data => {

        fs.writeFileSync(options.output, "");

        const out = fs.createWriteStream(options.output, {
            flags: "a"
        });

        for (let item of data ?? []) {
            out.write(`${item.prefix},${item.len},\n`);
        }
        out.end();

        console.log(`Done! See ${options.output}`);
    })
    .catch(error => {
        logger.log(error.message);
    });