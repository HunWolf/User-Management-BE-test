/* eslint-disable indent */
"use strict";


const DbMixin = require("../mixins/db.mixin");
const User = require("../models/user");
const bcrypt = require("bcrypt");
const crypto = require("crypto");



/**
 * @typedef {import('moleculer').ServiceSchema} ServiceSchema Moleculer's Service Schema
 * @typedef {import('moleculer').Context} Context Moleculer's Context
 */

/** @type {ServiceSchema} */
module.exports = {
	name: "users",

	/**
	 * Mixins 
	**/
	mixins: DbMixin("user"),

	model: User,

	/**
	 * Settings
	 */
	settings: {
		fields: ["_id", "email", "password", "addresses"],
	},

	/**
	 * Actions
	 */
	actions: {
		registration: {
			rest: "POST /",
			auth: false,
			params: {
				email: "email",
				address: {
					type: "string",
					empty: false
				},
				password: {
					type: "string",
					empty: false,
					pattern: /^(?=.*[0-9])(?=.*[!@#$%^&*])(?=.*[A-Z])(?=.*[a-z]).{8,}$/g,
				}
			},

			async handler(ctx) {
				try {
					const { email, password, address } = ctx.params;

					const exists = await this.adapter.findOne({ email });

					if (exists) {
						throw new Error("USER_EXISTS");
					}

					const userData = {
						email,
						password: this.hashPassword(password),
						token: this.generateToken()
					};

					const user = await this.adapter.insert(userData);

					user.addresses.push({ address });

					await user.save();

					return this.formatUser(user);

				} catch (error) {
					this.errorHandler(error);
				}
			}
		},

		login: {
			rest: "POST /login",
			auth: false,
			params: {
				email: "email",
				password: {
					type: "string",
					empty: false
				}
			},

			async handler(ctx) {
				try {
					const { email, password } = ctx.params;

					const user = await this.adapter.findOne({ email });

					if (!user) {
						throw new Error("EMAIL OR PASSWORD INVALID");
					}

					const passwordValidation = this.comparePassword(
						password,
						user.password
					);

					if (!passwordValidation) {
						throw new Error("EMAIL OR PASSWORD INVALID");
					}

					await this.adapter.updateById(user._id, { token: this.generateToken() });

					await user.save();

					return this.formatUser(user);

				} catch (error) {
					this.errorHandler(error);
				}
			}
		},

		listUsers: {
			rest: "GET /",
			auth: false,

			async handler() {
				try {
					const result = await this.adapter.find({});

					const users = result.map((x) => this.formatUser(x));

					return users;

				} catch (error) {
					this.errorHandler(error);
				}
			}
		},

		listUserProfile: {
			rest: "GET /profile",

			async handler(ctx) {

				const { user } = ctx.meta;

				try {
					const profile = await this.adapter.findById(user._id);

					return this.formatUser(profile);

				} catch (error) {
					throw new Error("INVALID_ID");
				}
			}
		},

		listUserAddress: {
			rest: "GET /:_id/address",
			params: {
				_id: {
					type: "string",
					empty: false
				}
			},

			async handler(ctx) {

				const { user } = ctx.meta;

				try {
					return user.addresses;

				} catch (error) {
					this.errorHandler(error);
				}
			}
		},

		profileUpdate: {
			rest: "PUT /:_id",
			params: {
				_id: {
					type: "string",
					empty: false
				},
				email: "email",
				password: {
					type: "string",
					pattern: /^(?=.*[0-9])(?=.*[!@#$%^&*])(?=.*[A-Z])(?=.*[a-z]).{8,}$/g,
				}
			},

			async handler(ctx) {

				const { _id, email } = ctx.params;

				try {
					const exists = await this.adapter.findOne({ email });

					if (exists) {
						throw new Error("EMAIL_ALREADY_IN_USE");
					}

					const profile = await this.adapter.findById({ _id });

					const userData = this.validateUserParams(ctx.params, profile);

					const user = await this.adapter.updateById(_id, userData);

					await user.save();

					return this.formatUser(user);

					// éles környezetben itt egy elfelejtett jelszó email kellene

				} catch (error) {
					this.errorHandler(error);
				}
			}
		},

		deleteUser: {
			rest: "DELETE /:_id",
			params: {
				_id: {
					type: "string",
					empty: false
				},
			},

			async handler(ctx) {
				const { _id } = ctx.params;

				try {
					await this.adapter.removeById({ _id });
					return ("Success");

				} catch (error) {
					this.errorHandler(error);
				}
			}
		},

		addressCreate: {
			rest: "PUT /:_id/newaddress",
			_id: {
				type: "string",
				empty: false
			},
			address: {
				type: "string",
				empty: false
			},

			async handler(ctx) {

				const { _id, address } = ctx.params;

				try {
					const profile = await this.adapter.findById({ _id });

					if (profile.addresses.findIndex(item => item.address === address) !== -1) {
						throw new Error("ADDRESS_ALREADY_EXISTS");
					}

					profile.addresses.push({ address });

					await profile.save();

					return this.formatUser(profile);

				} catch (error) {
					this.errorHandler(error);
				}
			}
		},

		addressUpdate: {
			rest: "PUT /:_id/updateaddress",
			params: {
				_id: {
					type: "string",
					empty: false
				},
				addressId: {
					type: "string",
					empty: false
				},
				address: {
					type: "string",
					empty: false
				}
			},

			async handler(ctx) {

				const { addressId, address } = ctx.params;

				try {
					const user = await User.findOneAndUpdate(
						{ "addresses._id": addressId },
						{
							$set: { "addresses.$.address": address }
						}, { returnDocument: "after" }

					);

					await user.save();

					return this.formatUser(user);

				} catch (error) {
					throw new Error("ADDRESS_ID_NOT_FOUND");
				}
			}
		},

		deleteAddress: {
			rest: "PUT /:_id/deleteaddress",
			params: {
				_id: {
					type: "string",
					empty: false
				},
				addressId: {
					type: "string",
					empty: false
				},
			},

			async handler(ctx) {
				const { addressId } = ctx.params;

				try {
					const user = await User.findOneAndUpdate(
						{ "addresses._id": addressId },
						{
							$pull: { addresses: { _id: addressId } }
						}, { returnDocument: "after" }

					);

					return this.formatUser(user);

				} catch (error) {
					throw new Error("ADDRESS_ID_INVALID");
				}
			}
		},

		findByAuthToken: {
			params: {
				token: {
					type: "string",
					empty: false,
				},
			},
			async handler(ctx) {
				const { token } = ctx.params;
				try {
					const user = await this.adapter.findOne({ "token": token });
					return user;

				} catch (error) {
					this.errorHandler(error);
				}
			}
		},
	},

	/**
	 * Methods
	 */
	methods: {

		errorHandler(error) {
			console.log("\n>>>>>>>>> [ERROR]");
			console.log(error);
			throw error;
		},

		formatUser(userData) {
			const user = {
				email: userData?.email,
				addresses: userData.addresses,
			};

			return user;
		},


		hashPassword(str) {
			return bcrypt.hashSync(str, 15);
		},

		comparePassword(password, hash) {
			return bcrypt.compareSync(password, hash);
		},

		validateUserParams(params, user) {
			const validate = Object.keys(params).filter(key => params[key] !== user[key]);
			return {
				email: validate.includes("email") ? params.email : undefined,
				password: validate.includes("password") ? this.comparePassword(
					params.password,
					user.password
				) ? undefined : this.hashPassword(params.password) : undefined

			};
		},

		generateToken() {
			return crypto.randomBytes(64).toString("hex");
		},
	},

};
