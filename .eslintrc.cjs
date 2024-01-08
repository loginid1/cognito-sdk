// eslint-disable-next-line no-undef
module.exports = {
	env: {browser: true, es2020: true},
	extends: [
		'eslint:recommended',
		'plugin:@typescript-eslint/recommended',
	],
	parser: '@typescript-eslint/parser',
	parserOptions: {ecmaVersion: 'latest', sourceType: 'module'},
	rules: {
		'quotes': ['error', 'single'],
		'semi': ['error', 'never'],
		'indent': ['error', 2],
		'no-multi-spaces': ['error'],
		'eol-last': ['error', 'always'],
		'sort-imports': ['error', {
			'ignoreCase': true,
			'ignoreDeclarationSort': true,
			'ignoreMemberSort': false,
			'memberSyntaxSortOrder': ['none', 'all', 'multiple', 'single'],
			'allowSeparatedGroups': false
		}]
	},
}
