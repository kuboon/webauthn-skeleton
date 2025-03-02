import { FileDB, Document } from "../deps.ts";
import { IToken } from "../utils/token.ts";

interface IAuthenticator extends Document {
    credId: string,
    publicKey: string,
    type: string,
    transports: string[],
    counter: number,
    created: Date,
}

// main.ts
interface IUser extends Document {
    userName?: string;
    name?: string;
    registered?: boolean;
    id?: string;
    authenticators?: IAuthenticator[];
    oneTimeToken?: IToken;
    recoveryEmail?: string;
}

// https://deno.land/x/filedb@0.0.6
const database = new FileDB({ rootDir: "./db/data", isAutosave: true });

// Example
// const users = await database.getCollection<IUser>("users"); // implicitly create and get User collection

export { database };
export type { IUser, IAuthenticator };

export async function getUser(userName: string) {
    const users = await database.getCollection<IUser>("users");
    return users.findOne({ userName });
}
export async function updateUser(userName: string, updates: IUser) {
    const users = await database.getCollection<IUser>("users");
    return users.updateOne({ userName }, updates);
}
export async function createUser(user: IUser) {
    const users = await database.getCollection<IUser>("users");
    return users.insertOne(user);
}
