#include <string.h>
#include <jni.h>

jstring Java_com_smit_jollen_jniDemo_MainActivity_helloWorldFromJNI(JNIEnv *env, jobject thiz)
{
    return (*env)->NewStringUTF(env, "Hello World! I'm from JNI.");
}
