export class DecryptError extends Error {
    constructor(){
        super("DecryptError");
        this.name = "DecryptError";
    }
}

export class InvalidRecoveryPhraseError extends Error {
    constructor(){
        super("InvalidRecoveryPhraseError");
        this.name = "InvalidRecoveryPhraseError";
    }
}