import JSZip from "jszip";

/**
 * Convierte un objeto JSZip a un archivo.
 *
 * @param file  - El objeto JSZip a convertir.
 * @returns  - Una promesa que se resuelve con el archivo convertido.
 */
const jsZipObjectToFile = async (file: JSZip.JSZipObject): Promise<File> => {
    const blob = await file.async("blob");

    return new File([blob], file.name, {
        type: blob.type || "application/octet-stream",
    });
};

/**
 * Carga un zip y devuelve los archivos que contiene.
 *
 * @param file  - El archivo zip a cargar.
 * @returns  - Una promesa que se resuelve con un array de archivos. [.json, .bin[], .js]
 */
export const loadZip = async (file: File): Promise<[File, File[], File]> => {
    const zip = await JSZip.loadAsync(file);
    const junk = /(^|\/)(__MACOSX|\.DS_Store|\.?_\w+)/;
    const jsonFiles = zip
        .file(/\.json$/)
        .filter(({ name }) => !junk.test(name));
    const binFiles = zip.file(/\.bin$/).filter(({ name }) => !junk.test(name));
    const scriptFiles = zip
        .file(/\.js$/)
        .filter(({ name }) => !junk.test(name));

    // Comprobar que hay un solo archivo json, al menos uno binario y un solo script
    if (
        jsonFiles.length !== 1 ||
        binFiles.length < 1 ||
        scriptFiles.length !== 1
    )
        throw new Error("Invalid zip file");

    // Convertir los archivos a File
    return Promise.all([
        jsZipObjectToFile(jsonFiles[0]),
        Promise.all(binFiles.map((file) => jsZipObjectToFile(file))),
        jsZipObjectToFile(scriptFiles[0]),
    ]);
};
