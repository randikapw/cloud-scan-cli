import fs from "fs"

class FileUtils {
    #logger;
    constructor(logger) {
        this.#logger = logger;
    }

    getJsonFromFile (path) {
        return JSON.parse(fs.readFileSync(path).toString());
    }
    
    writeJsonToFile (outfilepath, jsonObject) {
        const jsonStr = JSON.stringify(jsonObject, null, 2);
        fs.writeFileSync(outfilepath, jsonStr);
        console.log(`File write completed.`);
        return outfilepath;
    }
    
    mkDirIfNotExist(dirPath, shortName) {
        if (!fs.existsSync(dirPath)) {
            shortName = shortName ? `'${shortName}' d`: 'D';
            console.warn(`${shortName} direcotory '${dirPath}' is not avaialbe. Hence creating it rightnow`)
            fs.mkdirSync(dirPath, {recursive: true})
        }
    }

}

export default FileUtils