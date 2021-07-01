from django.http import JsonResponse
from rest_framework import status


def json_401(msg: str = ''):
    return JsonResponse(
        {
            'detail': msg
        }, status=status.HTTP_401_UNAUTHORIZED
    )


def json_400(msg: str = ''):
    return JsonResponse(
        {
            'detail': msg
        }, status=status.HTTP_400_BAD_REQUEST
    )


def json_200(msg: str = ''):
    return JsonResponse(
        {
            'detail': msg
        }, status=status.HTTP_200_OK
    )


def json_data_200(data: dict, msg: str = ''):
    return JsonResponse(
        {
            'detail': msg,
            'data': data,
        }, status=status.HTTP_200_OK
    )


def msg_with_data_400(data: dict, msg: str = ''):
    return JsonResponse(
        {
            'detail': msg,
            'data': data,
        }, status=status.HTTP_400_BAD_REQUEST
    )
