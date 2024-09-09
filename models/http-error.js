class HttpError extends Error{
    constructor(messsge, errorCode){
        super(messsge);
        this.code = errorCode;
    }
}

module.exports = HttpError;