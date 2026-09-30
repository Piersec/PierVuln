export function visibleText(value: string | null | undefined): string {
	return value?.replace(/wazuh/gi, (term) => term[0] === term[0].toUpperCase() ? "Indexador" : "indexador") ?? "";
}
