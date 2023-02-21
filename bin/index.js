#!/usr/bin/env node

import yargs from "yargs";
import vault from "./vault.js";
import config from "config";
import fs from "fs";
import { cronSchedule } from "./scheduler.js/scheduler.js";
import DefectDojo from "./defectDojo.js";
import FileUtils from "./fileUtils.js";
import CloudSploit from "./scanners/cloudsploit.js";
import moment from "moment/moment.js";
import defaultLogger from "./logger/logger.js";

let logger = defaultLogger;
const commandIdentifier = "cloudscan";

const args = yargs(process.argv.slice(2))
    .usage(`${commandIdentifier} [-p product name] [-c configfile path] -- one of configs(-c or -p) is required -c have the priority`)
    .option("p", { alias: "product", describe: "product name", type: "string", demandOption: false })
    .option("c", { alias: "config", describe: "configuration json file path", type: "string", demandOption: false })
    .argv

console.debug(args)

let productName = args.p;
let scanConfigs;

const profileRootDir = config.get("profiles.profileRootDir");
const profileConfigDirName = config.get("profiles.configDirName");
const profileReportsDirName = config.get("profiles.reportsDirName");


async function validateArguments() {
    const fsu = new FileUtils(logger);
    let confArg = args.c;
    if (confArg) {
        confArg = fsu.getJsonFromFile(confArg)
        productName = confArg?.product?.name;
        if (!productName) {
            throw new Error("Invalid configuration file! 'product.name' not found in configs");
        }

    }
    const scanConfigDir = `${profileRootDir}/${productName}/${profileConfigDirName}`
    const scanConfigPath = `${scanConfigDir}/scanconfigs.json`
    // const secretName = `cloudscan.product.${productName}.creds`
    const secretName = productName;
    if (fs.existsSync(scanConfigPath)) {
        if (confArg) {
            logger.info(`Configuration for product '${productName}' is already avaialbe and this will run with existing configs. if you want to update configs please user '${commandIdentifier} conf' command`);
        }
        let configBuild = fsu.getJsonFromFile(scanConfigPath);
        const credStr = await vault.getSecret(secretName);
        configBuild.credentials = JSON.parse(credStr);
        deepValidate(configBuild);
        scanConfigs = configBuild;

    } else if (confArg) {
        deepValidate(confArg);
        scanConfigs = confArg;
        logger.info("New product configuration found. Registering new product to configs")
        const credentials = scanConfigs.credentials;
        if (credentials) {
            logger.info(`Securing credentials provided by configs`);
            const secretValues = JSON.stringify(scanConfigs.credentials);
            await vault.setSecret(secretName, secretValues);
        }
        const configWithoudCreds = { company: scanConfigs.company, product: scanConfigs.product, scans: scanConfigs.scans }
        delete configWithoudCreds.credentials;
        const scnCfgStr = JSON.stringify(configWithoudCreds, null, 2);
        
        fsu.mkDirIfNotExist(scanConfigDir)
        fs.writeFileSync(scanConfigPath, scnCfgStr);
        logger.info(`File write completed.`);
    } else {
        const msg = `Cannot find internal configs for the product '${productName}'. Please use ${commandIdentifier} -c with valid configuration file.`;
        throw new Error(msg);
    }

    function deepValidate(configs) {
        //cloudsploit config validation
        if (configs?.scans?.cloudsploit) {
            CloudSploit.validateConfigs(configs);
        }

    }

}



function validateAppConfigs() {
    const fsu = new FileUtils(logger);
    fsu.mkDirIfNotExist(profileRootDir, "profileRootDir");
    const cloudSploitRootDir = config.get("cloudsploit.rootDir");
    const cloudsploitpackage = `${cloudSploitRootDir}/package.json`
    if (fs.existsSync(cloudsploitpackage)) {
        const pkg = fsu.getJsonFromFile(cloudsploitpackage);
        if (pkg?.name !== "cloudsploit") {
            throw new Error("Invalid cloudsplit root directory: invalid package.json. Are you refering to deferent node project?");
        }
    } else {
        throw new Error("Invalid cloudsplit root directory. Cannot find cloudsploit package.json");
    }
}

function funprogress() {
    let dots = ''
    process.stdout.write(`Loading `)

    let tmrID = setInterval(() => {
        dots += '.'
        process.stdout.write(`\rLoading ${dots}`)
    }, 1000)

    setTimeout(() => {
        clearInterval(tmrID)
        console.debug(`\rLoaded in [3500 ms]`)
    }, 3500)
}

async function executeScans() {
    const now = moment().format("YYYYMMDDhhmm");
    const seesionId = `${productName}-${now}`
    logger = logger.child({"sessionId" : seesionId})
    
    logger.info(`#START NEW SCAN withSessionId '${seesionId}'`)

    const engagementName = 'DefaultEngament'
    const reportsDirectory = `${profileRootDir}/${productName}/${profileReportsDirName}/${engagementName}/${now}`;

    const accounts = scanConfigs.scans.cloudsploit.accounts
    const defectdojo = new DefectDojo(logger);
    for (let index = 0; index < accounts.length; index++) {
        const account = accounts[index];
        try {
            
            const exeConfig = {...account, credentials: scanConfigs.credentials[account.credentialID]}
            const cloudsploit = new CloudSploit(logger);
            const cloudsploitScanOutput = await cloudsploit.executeScan(exeConfig, reportsDirectory);
            await defectdojo.authenticate();
            let product = await defectdojo.getProductsByName(productName, true);
            if (!product) {
                logger.info(`Product with name ${productName} is not currently exist`)
                product = await defectdojo.createProduct(productName);
            }
            const engagement = await defectdojo.getEngagementsByName(engagementName, product.id, true);
            if (!engagement) {
                logger.info(`Engagement with name ${engagementName} is not currently exist`)
                await defectdojo.createEngagement(engagementName, product.id)
            }
            await defectdojo.importScan(productName, engagementName, cloudsploitScanOutput);
        } catch (error) {
            logger.error(error.message);
            logger.error(error)
        }
    }
    logger.info(`#SCAN withSessionId '${seesionId}' is completed`)

}

async function start() {
    logger.debug
    logger.debug(`Environment: ${config.util.getEnv('NODE_ENV')}`)
    logger.debug(`ConfigLocation: ${config.util.getEnv('NODE_CONFIG_DIR')}`)
    logger.debug(`Target Dojo host: ${DefectDojo.host}`)
    validateAppConfigs();
    await validateArguments();
    await executeScans();
    const cronJob = config.get("scheduling.scancron")
    cronSchedule(cronJob, executeScans);
}
start();