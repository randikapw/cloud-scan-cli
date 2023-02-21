import winston, { format } from "winston";
import config from "config";

const baseLogDir = config.get("logger.baseDir");
const baseLogFileName = config.get("logger.baseFileName");
const defaultLogger = winston.createLogger({
    format: format.combine(
        format.timestamp({
            format: 'YYYY-MM-DD HH:mm:ss'
        }),
        format.errors({ stack: true }),
        format.splat(),
        format.json()
    ),
    transports: [
        new winston.transports.File({ filename: `${baseLogDir}/${baseLogFileName}` })
    ]
});

if (config.get("logger.enableConsole")) {
    defaultLogger.add(new winston.transports.Console({
        format: format.simple()
    }))
}

export default defaultLogger;
