package ai.reveng.toolkit.ghidra.core.services.api.types.binsync;

import ai.reveng.model.FunctionInfoOutput;
import org.json.JSONObject;

/**
 * {
 *     "func_types": {
 *       "stack_vars": null,
 *       "size": 107,
 *       "last_change": null,
 *       "name": "FUN_0010203b",
 *       "header": {
 *         "args": {
 *           "0x0": {
 *             "offset": 0,
 *             "size": 8,
 *             "last_change": null,
 *             "name": "param_1",
 *             "type": "long *"
 *           },
 *           "0x1": {
 *             "offset": 1,
 *             "size": 8,
 *             "last_change": null,
 *             "name": "param_2",
 *             "type": "char * *"
 *           }
 *         },
 *         "last_change": null,
 *         "name": "FUN_0010203b",
 *         "addr": 8251,
 *         "type": "int"
 *       },
 *       "addr": 8251,
 *       "type": "int"
 *     },
 *     "func_deps": [
 *         {
 *           "last_change": null,
 *           "name": "stat.h/stat64",
 *           "size": 144,
 *           "members": {
 *             "0x0": {
 *               "last_change": null,
 *               "name": "st_dev",
 *               "offset": 0,
 *               "type": "__dev_t",
 *               "size": 8
 *             },
 *             "0x8": {
 *               "last_change": null,
 *               "name": "st_ino",
 *               "offset": 8,
 *               "type": "__ino64_t",
 *               "size": 8
 *             },
 *             "0x10": {
 *               "last_change": null,
 *               "name": "st_nlink",
 *               "offset": 16,
 *               "type": "__nlink_t",
 *               "size": 8
 *             },
 *             "0x18": {
 *               "last_change": null,
 *               "name": "st_mode",
 *               "offset": 24,
 *               "type": "__mode_t",
 *               "size": 4
 *             },
 *             "0x1c": {
 *               "last_change": null,
 *               "name": "st_uid",
 *               "offset": 28,
 *               "type": "__uid_t",
 *               "size": 4
 *             },
 *             "0x20": {
 *               "last_change": null,
 *               "name": "st_gid",
 *               "offset": 32,
 *               "type": "__gid_t",
 *               "size": 4
 *             },
 *             "0x24": {
 *               "last_change": null,
 *               "name": "__pad0",
 *               "offset": 36,
 *               "type": "int",
 *               "size": 4
 *             },
 *             "0x28": {
 *               "last_change": null,
 *               "name": "st_rdev",
 *               "offset": 40,
 *               "type": "__dev_t",
 *               "size": 8
 *             },
 *             "0x30": {
 *               "last_change": null,
 *               "name": "st_size",
 *               "offset": 48,
 *               "type": "__off_t",
 *               "size": 8
 *             },
 *             "0x38": {
 *               "last_change": null,
 *               "name": "st_blksize",
 *               "offset": 56,
 *               "type": "__blksize_t",
 *               "size": 8
 *             },
 *             "0x40": {
 *               "last_change": null,
 *               "name": "st_blocks",
 *               "offset": 64,
 *               "type": "__blkcnt64_t",
 *               "size": 8
 *             },
 *             "0x48": {
 *               "last_change": null,
 *               "name": "st_atim",
 *               "offset": 72,
 *               "type": "timespec",
 *               "size": 16
 *             },
 *             "0x58": {
 *               "last_change": null,
 *               "name": "st_mtim",
 *               "offset": 88,
 *               "type": "timespec",
 *               "size": 16
 *             },
 *             "0x68": {
 *               "last_change": null,
 *               "name": "st_ctim",
 *               "offset": 104,
 *               "type": "timespec",
 *               "size": 16
 *             },
 *             "0x78": {
 *               "last_change": null,
 *               "name": "__unused",
 *               "offset": 120,
 *               "type": "long[3]",
 *               "size": 24
 *             }
 *           }
 *         },
 *         {
 *           "last_change": null,
 *           "name": "time.h/timespec",
 *           "size": 16,
 *           "members": {
 *             "0x0": {
 *               "last_change": null,
 *               "name": "tv_sec",
 *               "offset": 0,
 *               "type": "__time_t",
 *               "size": 8
 *             },
 *             "0x8": {
 *               "last_change": null,
 *               "name": "tv_nsec",
 *               "offset": 8,
 *               "type": "long",
 *               "size": 8
 *             }
 *           }
 *         },
 *         {
 *           "last_change": null,
 *           "name": "types.h/__mode_t",
 *           "type": "uint"
 *         },
 *         {
 *           "last_change": null,
 *           "name": "types.h/__gid_t",
 *           "type": "uint"
 *         },
 *         {
 *           "last_change": null,
 *           "name": "types.h/__off_t",
 *           "type": "long"
 *         },
 *         {
 *           "last_change": null,
 *           "name": "types.h/__uid_t",
 *           "type": "uint"
 *         },
 *         {
 *           "last_change": null,
 *           "name": "types.h/__time_t",
 *           "type": "long"
 *         },
 *         {
 *           "last_change": null,
 *           "name": "types.h/__dev_t",
 *           "type": "ulong"
 *         },
 *         {
 *           "last_change": null,
 *           "name": "types.h/__blksize_t",
 *           "type": "long"
 *         },
 *         {
 *           "last_change": null,
 *           "name": "types.h/__nlink_t",
 *           "type": "ulong"
 *         },
 *         {
 *           "last_change": null,
 *           "name": "types.h/__blkcnt64_t",
 *           "type": "long"
 *         },
 *         {
 *           "last_change": null,
 *           "name": "types.h/__ino64_t",
 *           "type": "ulong"
 *         }
 *       ]
 *   },
 *
 *   Consists of:
 *   - a regular BinSync Function Artifact in the `func_types` field
 *   - an array of unclear types in the `func_deps` field
 *
 *  This object isn't part of the BinSync types
 *  The func_deps members are either typedefs or structures
 *
 * @deprecated see {@link FunctionInfoOutput}
 */
@Deprecated
public record FunctionDataTypeMessage(
        FunctionArtifact func_types,
        FunctionDependencies func_deps
) {
    public static FunctionDataTypeMessage fromJsonObject(JSONObject dataTypes) {
        return new FunctionDataTypeMessage(
                FunctionArtifact.fromJsonObject(dataTypes. getJSONObject("func_types")),
                FunctionDependencies.fromJsonObject(dataTypes.getJSONArray("func_deps"))

        );
    }
    public boolean hasDependencies() {
        return func_deps != null;
    }

    public String functionName() {
        return func_types.header().name();
    }

}
