// Code generated by protoc-gen-go-ttrpc. DO NOT EDIT.
// source: github.com/containerd/containerd/api/services/version/v1/version.proto
package version

import (
	context "context"
	ttrpc "github.com/containerd/ttrpc"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

type TTRPCVersionService interface {
	Version(context.Context, *emptypb.Empty) (*VersionResponse, error)
}

func RegisterTTRPCVersionService(srv *ttrpc.Server, svc TTRPCVersionService) {
	srv.RegisterService("containerd.services.version.v1.Version", &ttrpc.ServiceDesc{
		Methods: map[string]ttrpc.Method{
			"Version": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) {
				var req emptypb.Empty
				if err := unmarshal(&req); err != nil {
					return nil, err
				}
				return svc.Version(ctx, &req)
			},
		},
	})
}

type ttrpcversionClient struct {
	client *ttrpc.Client
}

func NewTTRPCVersionClient(client *ttrpc.Client) TTRPCVersionService {
	return &ttrpcversionClient{
		client: client,
	}
}

func (c *ttrpcversionClient) Version(ctx context.Context, req *emptypb.Empty) (*VersionResponse, error) {
	var resp VersionResponse
	if err := c.client.Call(ctx, "containerd.services.version.v1.Version", "Version", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}