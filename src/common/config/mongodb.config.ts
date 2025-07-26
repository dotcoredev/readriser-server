import { registerAs } from "@nestjs/config";
import { MongooseModuleOptions } from "@nestjs/mongoose";

export default registerAs<MongooseModuleOptions>("mongodb", () => ({
	uri: process.env.MONGODB_URI,
}));
