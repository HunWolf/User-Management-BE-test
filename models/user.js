const mongoose = require("mongoose");

const addressSchema = new mongoose.Schema(
	{
		address: { type: String },
	}
);

const UserSchema = new mongoose.Schema(
	{
		email: { type: String },
		password: { type: String },
		addresses: { type: [addressSchema] },
		token: { type: String }, //éles környezetben ide kéne egy date is, mert időszakosan törölni kell a lejárt tokeneket
	},
	{ timestamps: true }
);

module.exports = mongoose.model("User", UserSchema);