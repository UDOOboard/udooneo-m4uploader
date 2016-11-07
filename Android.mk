
LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_SHARED_LIBRARIES := liblog libcutils
LOCAL_SRC_FILES:= mqx_upload_on_m4SoloX.c
LOCAL_MODULE := udooneo-m4uploader
LOCAL_MODULE_TAGS := optional
include $(BUILD_EXECUTABLE)
