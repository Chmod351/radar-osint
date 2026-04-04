type LogLevel = "INFO" | "WARN" | "ERROR" | "DEBUG";

class Logger {
  private isTest = process.env.NODE_ENV === "test";

  private formatMessage(level: LogLevel, context: string, message: string): string {
    const ts = new Date().toISOString();
    const color = this.getColor(level);
    const reset = "\x1b[0m";
    return `${color}[${ts}] [${level}] [${context}]${reset} ${message}`;
  }

  private getColor(level: LogLevel): string {
    switch (level) {
    case "ERROR": return "\x1b[31m"; // Rojo
    case "WARN":  return "\x1b[33m"; // Amarillo
    case "INFO":  return "\x1b[36m"; // Cian
    case "DEBUG": return "\x1b[90m"; // Gris
    default:      return "\x1b[0m";
    }
  }

  info(context: string, message: string) {
    if (!this.isTest) console.log(this.formatMessage("INFO", context, message));
  }

  warn(context: string, message: string) {
    if (!this.isTest) console.warn(this.formatMessage("WARN", context, message));
  }

  error(context: string, message: string, error?: unknown) {
    // Los errores siempre se muestran, incluso en test si querés ver fallos críticos
    console.error(this.formatMessage("ERROR", context, message));
    if (error instanceof Error) {
      console.error(`\x1b[31m[STACK]\x1b[0m ${error.stack}`);
    }
  }

  debug(context: string, message: string) {
    if (process.env.DEBUG && !this.isTest) {
      console.log(this.formatMessage("DEBUG", context, message));
    }
  }
}

export const logger = new Logger();
