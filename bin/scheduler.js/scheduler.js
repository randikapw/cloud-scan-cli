import cron from "node-cron";

export function cronSchedule(cronStr, func){
    const sch = cron.schedule(cronStr,func);
}