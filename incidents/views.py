import json

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView


class IncidentViewSet(APIView):
    """
    API endpoint that allows users to be viewed or edited.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    @staticmethod
    def get(request, *args, **kwargs):
        """
        Retrieve the prepared dataset.

        :return: (JSON) The incident reports and a 200 status on success
        """
        with open('incident_report.json', 'r') as fp:
            data = json.load(fp)

        return Response(data, status=status.HTTP_200_OK)

    @staticmethod
    def post(request, *args, **kwargs):
        return Response(None, status=status.HTTP_501_NOT_IMPLEMENTED)

    @staticmethod
    def put(request, *args, **kwargs):
        return Response(None, status=status.HTTP_501_NOT_IMPLEMENTED)

    @staticmethod
    def delete(request, *args, **kwargs):
        return Response(None, status=status.HTTP_501_NOT_IMPLEMENTED)
