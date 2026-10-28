/** Expresión regular para obtener los comentarios */
const COMMENT_REGEX = /\/\*[\s\S]*?\*\/|\/\/.*/g;
/** Expresión regular para obtener los nombres de las funciones de la biblioteca */
const LIBRARY_FUNCTIONS_REGEX =
    /(?:function|const|let|var)\s+((intcp(_router|_iot|_computer)?|cmd_[A-Za-z0-9$_]+|atk_[A-Za-z0-9$_]+))\s*=?\s*\([A-Za-z0-9$_,.\s]*\)\s*(?:=>)?\s*{/g;
/** Expresión regular para obtener los nombres de las funciones del modelo */
const MODEL_FUNCTIONS_REGEX =
    /(?:function|const|let|var)\s+((analyze))\s*=?\s*\([A-Za-z0-9$_,.\s]*\)\s*(?:=>)?\s*{/g;
/** Expresión regular para obtener los parámetros de las funciones */
const PARAMS_REGEX = /\(([^)]*)\)/;

/**
 * Función para parsear un script de JavaScript y obtener las funciones que sean interceptores, comandos o ataques.
 *
 * @param script - El script de JavaScript a parsear.
 * @return - Una función que contiene las funciones interceptores, comandos o ataques.
 */
export const parseLibraryScript = (script: string): Function => {
    // Eliminar comentarios
    script = script.replace(COMMENT_REGEX, "");

    // Obtener los nombres de las funciones que sean interceptores, comandos o ataques
    const functions = [...script.matchAll(LIBRARY_FUNCTIONS_REGEX)].map(
        (e) => e[1],
    );

    // Exportar las funciones
    script = script.concat("\n", "return { ", functions.join(", "), " };\n");

    // Compilar el script
    return new Function(script);
};

/**
 * Funcion para parsear un script de JavaScript y obtener la funcion que sea para analizar el paquete.
 *
 * @param script - El script de JavaScript a parsear.
 * @returns - Una función que contiene la función para analizar el paquete.
 */
export const parseModelScript = (script: string): Function => {
    // Eliminar comentarios
    script = script.replace(COMMENT_REGEX, "");

    // Obtener la función que sea para analizar el paquete
    const functions = [...script.matchAll(MODEL_FUNCTIONS_REGEX)].map(
        (e) => e[1],
    );

    // Si no hay funciones para analizar el paquete, lanzar un error
    if (functions.length === 0)
        throw new Error("No se encontró la función analyze");

    // Exportar las funciones
    script = script.concat("\n", "return { analyze };\n");

    // Compilar el script
    return new Function("tf", "model", script);
};

/**
 * Funcion que te devuelve el numero de parametros de una funcion
 *
 * @param fn - La funcion a analizar.
 * @returns - El numero de parametros de la funcion, si hay un spread devuelve infinity.
 */
export const paramsCount = (fn: Function): number => {
    const fnStr = fn.toString();
    const paramsMatch = fnStr.match(PARAMS_REGEX);

    if (!paramsMatch) return 0;

    const params = paramsMatch[1].split(",").map((e) => e.trim());
    const spread = params.find((e) => e.includes("..."));

    return spread ? Infinity : params.length;
};
