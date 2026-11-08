export class DecryptError extends Error {
    constructor(){
        super("DecryptError");
        this.name = "DecryptError";
    }
}