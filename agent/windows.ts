import { importfunc } from "./native";

const RtlGetCurrentPeb = importfunc(null, "RtlGetCurrentPeb", 'pointer', []);