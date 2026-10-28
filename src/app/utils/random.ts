/**
 * Función para obtener un número entero aleatorio entre un rango.
 *
 * @param min Número mínimo (incluido).
 * @param max Número máximo (incluido).
 * @returns Número entero aleatorio entre min y max.
 */
export const randomInt = (min: number, max: number): number =>
    Math.floor(Math.random() * (max - min + 1)) + min;

/**
 * Función para obtener un string aleatorio de un tamaño determinado.
 *
 * @param size Tamaño del string.
 * @returns String aleatorio.
 */
export const randomString = (size: number): string => {
    const chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";

    for (let i = 0; i < size; i++)
        result += chars[randomInt(0, chars.length - 1)];
    return result;
};

/**
 * Función para obtener un número aleatorio con una media y una desviación estándar.
 *
 * @param mean Media del número.
 * @param stddev Desviación estándar del número.
 * @returns Número aleatorio con una media y una desviación estándar.
 */
export const randomMeanStd = (mean: number, stddev: number): number => {
    const rand = Math.random() + Math.random() + Math.random();

    return Math.max(1, Math.floor(mean + stddev * (rand - 1.5)));
};
